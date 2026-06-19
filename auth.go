//go:build !cli

package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const csrfTokenName = "_csrf"
const sessionCookieName = "_benmore_session"

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

// ===== SQLite-Persisted Sessions =====

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
	db.Exec("DELETE FROM _benmore_sessions WHERE expires_at < datetime('now')")
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

// EnsureAPITokensTable creates the persistent API tokens table.
func EnsureAPITokensTable(db *sql.DB) {
	db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_api_tokens (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		name TEXT NOT NULL,
		token_hash TEXT UNIQUE NOT NULL,
		scopes TEXT NOT NULL,
		last_used_at DATETIME,
		expires_at DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES _benmore_users(id)
	)`)
	db.Exec("CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON _benmore_api_tokens(token_hash)")
}

// NewSessionStore creates a session store backed by SQLite.
func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[string]*Session),
	}
}

// ResolveGroupID looks up the user's organization from the configured
// membership table. v2.5.10: returns string (was int64) so UUID/slug/
// opaque-ID tenant keys work natively. Empty string means "no group".
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
		LEFT JOIN _benmore_users u ON u.id = s.user_id
		WHERE s.id = ? AND s.expires_at > datetime('now')`,
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
func CleanExpiredSessions(db *sql.DB) {
	go func() {
		for {
			time.Sleep(15 * time.Minute)
			db.Exec("DELETE FROM _benmore_sessions WHERE expires_at < datetime('now')")
			db.Exec("DELETE FROM _benmore_api_tokens WHERE expires_at IS NOT NULL AND expires_at < datetime('now')")
		}
	}()
}

// ===== HMAC-Based CSRF Tokens =====

// generateCSRFToken creates a CSRF token derived from HMAC(secret, random_nonce + timestamp).
// No storage needed - validation recomputes the HMAC.
//
// This is the session-LESS variant kept for backward compatibility:
// pre-authentication pages (login / signup), the auto-injected <meta>
// tag rendered before a session exists, and every existing caller that
// has no *http.Request in scope still mint an unbound token here. Such
// tokens validate for any request (see authCSRFSign with sid="").
func generateCSRFToken() string {
	return authMintCSRFToken("")
}

// authMintCSRFToken mints a CSRF token, optionally bound to a session id.
// H-11: when sid != "" the session id is folded into the HMAC input (but
// NOT into the visible payload, so the wire format stays the legacy
// 3-part "nonce|ts|sig" and every existing parser/length check keeps
// working). A session-bound token only validates for requests carrying
// that same session (validateCSRF re-derives with the live session id),
// so a token minted for one user can no longer be replayed by another -
// the /api/_csrf endpoint is unauthenticated, so without binding one
// fetched token authenticated every user's mutations.
func authMintCSRFToken(sid string) string {
	nonce := generateToken(16)
	ts := fmt.Sprintf("%d", time.Now().Unix())
	payload := nonce + "|" + ts
	sig := authCSRFSign(payload, sid)
	return payload + "|" + sig
}

// authCSRFSign computes the HMAC over the token payload, binding it to a
// session id when provided. sid=="" reproduces the legacy unbound MAC so
// session-less tokens (and tokens minted before a session existed) stay
// valid - that's the back-compat path validateCSRF falls back to.
func authCSRFSign(payload, sid string) string {
	mac := hmac.New(sha256.New, []byte(serverSecret))
	mac.Write([]byte(payload))
	if sid != "" {
		// Domain-separate the session component so a "|"-bearing payload
		// can't be confused with the binding boundary.
		mac.Write([]byte("\x00sid\x00"))
		mac.Write([]byte(sid))
	}
	return hex.EncodeToString(mac.Sum(nil))
}

// authRawSessionID returns the raw session id the request is authenticating
// with (cookie first, then a non-prefixed Bearer session token), or "" when
// the request carries no session. Used to bind/validate CSRF tokens against
// the originating session. Persistent API tokens (bmr_ prefix) are exempt -
// those callers go through the isBearerAuth CSRF exemption anyway.
func authRawSessionID(r *http.Request) string {
	if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
		return c.Value
	}
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		tok := strings.TrimPrefix(auth, "Bearer ")
		if !strings.HasPrefix(tok, "bmr_") {
			return tok
		}
	}
	return ""
}

// isBearerAuth returns true if the request is authenticated by a Bearer
// token ONLY. Bearer-authenticated requests don't need CSRF protection
// since there's no cookie to ride on cross-site.
//
// A request that carries a session cookie does NOT qualify even when an
// Authorization header is also present (M1, 2026-06-11 audit): getSession
// prefers the cookie, so such a request is cookie-authenticated - and the
// old prefix-only check meant any attacker who could coax the browser into
// adding `Authorization: Bearer junk` (e.g. via fetch on an app with a
// CORS allowlist) skipped CSRF while still riding the victim's cookie.
// CLI / MCP / SDK clients never hold the session cookie, so they keep the
// exemption. The rare client that holds a stale cookie alongside a valid
// Bearer token must clear the cookie (or pass CSRF) - failing closed is
// the right default for an auth gate.
func isBearerAuth(r *http.Request) bool {
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		return false
	}
	if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
		return false
	}
	return true
}

// isSameOriginRequest returns true if the request's Origin header is
// absent OR matches r.Host. Used to gate cookie-credentialed long-lived
// channels (WebSocket / SSE) - browsers DO send Origin on those, but
// don't preflight, so without a server-side check an attacker page can
// open a WS/EventSource to our origin, the browser attaches our session
// cookie, and the attacker tab receives whatever we broadcast.
//
// Same-origin requests in the wild either omit Origin or send the
// page's origin. Cross-origin browser requests always send Origin set
// to the *attacker* page. Bearer-auth (CLI / native) sends no Origin
// and no cookies, so the no-Origin path stays open for those clients.
func isSameOriginRequest(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	// Compare host (incl. port) against the request's Host header.
	return strings.EqualFold(u.Host, r.Host)
}

// requireCSRF gates a mutation handler that accepts session-cookie auth.
// Bearer-authenticated requests (CLI / MCP / SDK) are exempt - there's no
// cookie to ride on for cross-origin abuse. Returns true when the handler
// should proceed; on false the caller must return immediately (response
// has already been written).
func requireCSRF(w http.ResponseWriter, r *http.Request) bool {
	if isBearerAuth(r) {
		return true
	}
	if validateCSRF(r) {
		return true
	}
	// Log enough to debug the two common causes without leaking the
	// token: header-presence, length, and the request shape. A page
	// served before BENMORE_SERVER_SECRET was set will fail here
	// because its HMAC was signed with a since-replaced ephemeral
	// secret - that case looks like "header present, valid length".
	hdr := r.Header.Get("X-CSRF-Token")
	formHas := r.FormValue(csrfTokenName) != ""
	log.Printf("requireCSRF: REJECT method=%s path=%s header_present=%t header_len=%d form_present=%t referer=%q",
		r.Method, r.URL.Path, hdr != "", len(hdr), formHas, r.Header.Get("Referer"))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(`{"error":"invalid csrf token"}`))
	return false
}

// isSafeNext returns true only if next is a same-origin relative path.
// Rejects "//evil.com" and "/\evil.com" - browsers treat both as
// protocol-relative URLs and would redirect off-site.
func isSafeNext(next string) bool {
	if len(next) < 1 || next[0] != '/' {
		return false
	}
	if len(next) >= 2 && (next[1] == '/' || next[1] == '\\') {
		return false
	}
	return true
}

// validateCSRF verifies a CSRF token's HMAC and checks it's not expired (24h).
func validateCSRF(r *http.Request) bool {
	reason, ok := validateCSRFReason(r)
	if !ok {
		log.Printf("validateCSRF: REJECT path=%s reason=%s ua=%q", r.URL.Path, reason, r.UserAgent())
	}
	return ok
}

// validateCSRFReason is the implementation; surfaces WHY the token was
// rejected so operators can debug stale-token-after-redeploy issues
// (the most common false-positive on this code path).
func validateCSRFReason(r *http.Request) (string, bool) {
	token := r.FormValue(csrfTokenName)
	if token == "" {
		token = r.Header.Get("X-CSRF-Token")
	}
	if token == "" {
		return "missing", false
	}

	parts := strings.SplitN(token, "|", 3)
	if len(parts) != 3 {
		return "malformed", false
	}

	nonce, tsStr, providedSig := parts[0], parts[1], parts[2]

	// CSRF origin gate (round-2 #2). The session cookie is SameSite=Lax so a
	// cross-site POST/fetch won't even carry it; this is the second layer and
	// is what actually stops a forged request - the HMAC token below is
	// defense-in-depth. A cross-site request must NOT be able to reach the HMAC
	// check (which would otherwise accept a session-less/unbound token lifted
	// from /api/_csrf or the page meta tag).
	//   - Origin present -> must match our Host.
	//   - Origin absent  -> consult Sec-Fetch-Site (sent by all modern
	//     browsers): reject cross-site / same-site. Earlier this treated a
	//     missing Origin as same-origin, which let a no-Origin cross-site POST
	//     through. A request with neither header (old/native client) still
	//     falls through to the token, preserving legitimate non-browser callers.
	if origin := r.Header.Get("Origin"); origin != "" {
		if u, err := url.Parse(origin); err != nil || !strings.EqualFold(u.Host, r.Host) {
			return "origin_mismatch", false
		}
	} else if sfs := r.Header.Get("Sec-Fetch-Site"); sfs == "cross-site" || sfs == "same-site" {
		return "sec_fetch_" + sfs, false
	}

	// Verify HMAC. H-11: prefer the session-bound MAC (token tied to the
	// request's originating session id) and fall back to the legacy
	// unbound MAC so tokens minted before a session existed (login/signup
	// pages, the pre-auth <meta> tag, and every session-less caller) keep
	// validating. A token bound to session A therefore can NOT be replayed
	// on session B - B's id won't reproduce A's signature, and the unbound
	// fallback won't match a bound signature either.
	payload := nonce + "|" + tsStr
	sid := authRawSessionID(r)
	boundSig := authCSRFSign(payload, sid)
	unboundSig := authCSRFSign(payload, "")
	if !hmac.Equal([]byte(providedSig), []byte(boundSig)) &&
		!hmac.Equal([]byte(providedSig), []byte(unboundSig)) {
		return "hmac_mismatch", false
	}

	// Check expiry (24 hours)
	var ts int64
	if _, err := fmt.Sscanf(tsStr, "%d", &ts); err != nil || ts == 0 {
		return "ts_unparseable", false
	}
	age := time.Now().Unix() - ts
	if age > 86400 {
		return fmt.Sprintf("expired_age=%ds", age), false
	}

	return "", true
}

// ===== Brute Force Protection =====

// EnsureLoginAttemptsTable creates the login attempts tracking table.
func EnsureLoginAttemptsTable(db *sql.DB) {
	db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_login_attempts (
		email TEXT NOT NULL,
		attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		success BOOLEAN DEFAULT 0
	)`)
	db.Exec("CREATE INDEX IF NOT EXISTS idx_login_attempts_email ON _benmore_login_attempts(email, attempted_at)")
}

// normalizeEmail lower-cases + trims an email-shaped identifier so
// `A@example.com` and `a@example.com` are the same account everywhere -
// store, lookup, and lockout key (2026-06-11 audit: case variation allowed
// duplicate accounts and lockout-counter evasion).
func normalizeEmail(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// recordLoginAttempt logs a login attempt. The key is normalized so an
// attacker can't dodge the lockout counter by case-varying the email.
func recordLoginAttempt(db *sql.DB, email string, success bool) {
	if _, err := db.Exec("INSERT INTO _benmore_login_attempts (email, success) VALUES (?, ?)", normalizeEmail(email), success); err != nil {
		log.Printf("ERROR recording login attempt: %s", err)
	}
	db.Exec("DELETE FROM _benmore_login_attempts WHERE attempted_at < datetime('now', '-1 hour')")
}

// isAccountLocked checks if an account has too many failed attempts since last success (within 15 min window).
// Only counts failures AFTER the most recent successful login, so a successful login resets the counter.
func isAccountLocked(db *sql.DB, email string) bool {
	email = normalizeEmail(email)
	var count int
	db.QueryRow(
		`SELECT COUNT(*) FROM _benmore_login_attempts
		 WHERE email = ? AND success = 0
		 AND attempted_at > COALESCE(
			(SELECT MAX(attempted_at) FROM _benmore_login_attempts WHERE email = ? AND success = 1),
			'1970-01-01'
		 )
		 AND attempted_at > datetime('now', '-15 minutes')`,
		email, email,
	).Scan(&count)
	return count >= 5
}

// authIPLockKey namespaces a client IP into the shared
// _benmore_login_attempts table so per-IP throttling reuses the same
// rolling-window machinery as the per-account lockout without a second
// table. The "ip:" prefix can never collide with a normalized email
// (emails always contain "@" and never a leading "ip:").
func authIPLockKey(ip string) string {
	return "ip:" + strings.ToLower(strings.TrimSpace(ip))
}

// authIsIPLocked reports whether a single source IP has accumulated too
// many failed login attempts in the rolling 15-minute window. This sits
// ALONGSIDE the per-account lockout (isAccountLocked): the account lock
// stops a focused attack on one victim, while this per-IP cap blunts a
// spray attack that rotates the username to dodge the per-account
// counter. The IP threshold is deliberately higher than the per-account
// one so shared-NAT / office-egress users aren't locked out by a few
// unrelated typos. Empty/unknown IPs are never locked (fail open - we
// must not wedge a whole deployment on a missing RemoteAddr).
func authIsIPLocked(db *sql.DB, ip string) bool {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return false
	}
	key := authIPLockKey(ip)
	var count int
	db.QueryRow(
		`SELECT COUNT(*) FROM _benmore_login_attempts
		 WHERE email = ? AND success = 0
		 AND attempted_at > datetime('now', '-15 minutes')`,
		key,
	).Scan(&count)
	return count >= authIPLoginLimit
}

// authIPLoginLimit is the per-IP failed-login ceiling in the 15-minute
// window. Higher than the per-account limit (5) so shared egress IPs
// tolerate a handful of unrelated bad logins before throttling.
const authIPLoginLimit = 25

// ===== Auth Middleware =====

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

// ===== Auth Routes =====

// RegisterAuthRoutes adds login, signup, logout routes.
func RegisterAuthRoutes(mux *http.ServeMux, app *App) {
	EnsureUsersTable(app.DB)
	EnsureSessionsTable(app.DB)
	EnsureLoginAttemptsTable(app.DB)
	EnsureUserRolesTable(app.DB)
	CleanExpiredSessions(app.DB)
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
			"SELECT id, created_at, expires_at, COALESCE(ip, '') AS ip, COALESCE(user_agent, '') AS user_agent FROM _benmore_sessions WHERE user_id = ? AND expires_at > datetime('now') ORDER BY created_at DESC",
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
			"SELECT id FROM _benmore_sessions WHERE user_id = ? AND expires_at > datetime('now')",
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
	err = app.DB.QueryRow("SELECT code, attempts FROM _benmore_otp WHERE email = ? AND expires_at > datetime('now')", otpKey).Scan(&storedCode, &attempts)
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
				if field == "" || field == "email" || field == "password" || field == "password_hash" || field == "username" {
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

	// Best-effort: if RESEND_API_KEY + RESEND_AUDIENCE_ID are set in
	// the app's env, add the new signup to that audience for marketing
	// emails. Fire-and-forget - never blocks the signup.
	go AddResendContact(app.Dir, email, r.FormValue("first_name"), r.FormValue("last_name"))

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

// ===== Cookie Helpers =====

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

// ===== Auth Helpers =====
// Auto-generated auth pages removed. Developer creates their own pages
// with type="login", type="signup", etc. Errors via ?error= query param.

// authRedirect redirects to an auth page path with an optional error message.
// Error is passed as a query param so the developer's template can show it
// via {{param_error}}. This replaces all auto-generated page rendering.
// authRedirect ends a failed auth attempt. For browser clients it
// 303s back to the auth page with ?error=…; for SPA / API clients
// that asked for JSON (Accept: application/json) it returns a JSON
// error body so they can render the message inline without a redirect
// dance - critical for React/raw apps where /login and /signup don't
// have server-rendered counterparts.
func authRedirect(w http.ResponseWriter, r *http.Request, path, errMsg string) {
	if wantsJSON(r) {
		status := http.StatusBadRequest
		if errMsg == "Invalid credentials" {
			status = http.StatusUnauthorized
		} else if strings.Contains(errMsg, "Too many") {
			status = http.StatusTooManyRequests
		}
		httpJSON(w, status, map[string]any{"ok": false, "error": errMsg})
		return
	}
	if errMsg != "" {
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		path += sep + "error=" + url.QueryEscape(errMsg)
	}
	http.Redirect(w, r, path, http.StatusSeeOther)
}

// mergeJSONBodyIntoForm reads a JSON request body and copies each
// top-level key into r.PostForm / r.Form, so subsequent r.FormValue
// lookups work uniformly whether the client sent
// application/x-www-form-urlencoded or application/json. Called by
// the auth handlers so bm.api.post('/signup', {...}) (which sends
// JSON) behaves identically to a native <form method="POST"> submit.
// No-ops when Content-Type isn't JSON. Body is capped at 1MB.
func mergeJSONBodyIntoForm(r *http.Request) {
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if !strings.Contains(ct, "application/json") {
		return
	}
	if r.Body == nil {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	r.Body.Close()
	if err != nil || len(body) == 0 {
		return
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return
	}
	// ParseForm initialises r.Form from the URL query (it won't read the
	// body since the content-type isn't form-encoded). Safe to call.
	_ = r.ParseForm()
	if r.PostForm == nil {
		r.PostForm = url.Values{}
	}
	if r.Form == nil {
		r.Form = url.Values{}
	}
	for k, v := range m {
		var s string
		switch x := v.(type) {
		case nil:
			s = ""
		case string:
			s = x
		case bool:
			if x {
				s = "true"
			} else {
				s = "false"
			}
		case float64:
			s = strconv.FormatFloat(x, 'f', -1, 64)
		default:
			b, _ := json.Marshal(x)
			s = string(b)
		}
		r.PostForm.Set(k, s)
		r.Form.Set(k, s)
	}
}

// wantsJSON returns true when the client has explicitly opted into a
// JSON response, either via `Accept: application/json` or by sending
// a JSON Content-Type. Standard browser form submissions send
// `Accept: text/html,...` so they keep the redirect flow; the SPA's
// bm.useAuth flow sends `Accept: application/json` and gets clean
// JSON errors instead of being redirected to a /login URL that has
// no server-side handler.
func wantsJSON(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		// Crude but adequate: prefer json only when it's listed
		// BEFORE text/html (or when html isn't mentioned at all).
		// Browsers list text/html first; explicit API clients list
		// json first.
		if !strings.Contains(accept, "text/html") {
			return true
		}
		jsonIdx := strings.Index(accept, "application/json")
		htmlIdx := strings.Index(accept, "text/html")
		if jsonIdx >= 0 && jsonIdx < htmlIdx {
			return true
		}
	}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return true
	}
	return false
}

// authSuccessJSON writes a successful-auth JSON response. The session
// cookie has already been set on `w` by the caller before invoking.
// Returns true when JSON was written so the caller knows to skip the
// http.Redirect.
func authSuccessJSON(w http.ResponseWriter, r *http.Request, app *App, userID int64) bool {
	if !wantsJSON(r) {
		return false
	}
	user := loadUserForJSON(app, userID)
	httpJSON(w, http.StatusOK, map[string]any{"ok": true, "user": user})
	return true
}

// isSensitiveUserColumn names columns that must never be returned over
// the wire as part of a user-object payload. The exact-match list covers
// the framework's own sensitive columns; the suffix/prefix patterns are
// a defensive net so a developer who adds e.g. `payment_token` or
// `internal_notes` doesn't accidentally leak it through loadUserForJSON
// or GET /api/_auth/profile. Defense in depth - apps that genuinely need
// to expose such a column should rename it.
func isSensitiveUserColumn(col string) bool {
	c := strings.ToLower(col)
	switch c {
	case "password_hash", "password", "totp_secret", "mfa_backup_codes",
		"backup_codes", "recovery_codes", "salt", "session_id", "csrf_token",
		// MFA bookkeeping - last TOTP submitted + timestamps. Exposing
		// them risks replay-attack analysis ("a code was used at T,
		// next codes are likely in this window"). Leaked under
		// /api/_auth/users in v2.7.11 first build; added here.
		"mfa_last_totp", "mfa_last_totp_at", "mfa_enrolled_at":
		return true
	}
	// Any column starting with mfa_ is bookkeeping - never expose.
	if strings.HasPrefix(c, "mfa_") {
		return true
	}
	for _, suf := range []string{"_hash", "_secret", "_token", "_key", "_password", "_pin"} {
		if strings.HasSuffix(c, suf) {
			return true
		}
	}
	for _, pre := range []string{"private_", "internal_", "secret_"} {
		if strings.HasPrefix(c, pre) {
			return true
		}
	}
	return false
}

// loadUserForJSON fetches the freshly-authenticated user's row for
// inclusion in the JSON response. Excludes columns flagged by
// isSensitiveUserColumn so a developer who adds a column like
// `payment_token` doesn't silently leak it.
func loadUserForJSON(app *App, userID int64) map[string]any {
	out := map[string]any{"id": userID}
	if app == nil || app.DB == nil {
		return out
	}
	rows, err := app.DB.Query("SELECT * FROM _benmore_users WHERE id = ?", userID)
	if err != nil {
		return out
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil || !rows.Next() {
		return out
	}
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	if err := rows.Scan(ptrs...); err != nil {
		return out
	}
	for i, c := range cols {
		if isSensitiveUserColumn(c) {
			continue
		}
		v := vals[i]
		if b, ok := v.([]byte); ok {
			v = string(b)
		}
		out[c] = v
	}
	return out
}

// baseURL returns the canonical base URL for email links.
// Uses the developer-configured SEO URL if available (trusted), otherwise
// falls back to r.Host (which can be spoofed via Host header).
func baseURL(app *App, r *http.Request) string {
	if app.Design != nil {
		if seoURL, ok := app.Design.SEO["url"]; ok && seoURL != "" {
			return strings.TrimRight(seoURL, "/")
		}
	}
	return fmt.Sprintf("%s://%s", protoOf(r), r.Host)
}

// securityLinkBaseURL is baseURL for links emailed as credentials (password
// reset, email verification). It must NOT be derived from the attacker-
// controllable Host / X-Forwarded-Proto headers when an operator-configured
// origin exists: a host-header-poisoning attacker could otherwise make the
// genuine reset email point the token at their domain (round-2 #5 - pre-auth
// account takeover). Preference: configured seo.url -> BENMORE_PUBLIC_URL /
// CORS_ORIGIN -> request host (logged, so operators see the unsafe fallback).
func securityLinkBaseURL(app *App, r *http.Request) string {
	if app.Design != nil {
		if seoURL, ok := app.Design.SEO["url"]; ok && seoURL != "" {
			return strings.TrimRight(seoURL, "/")
		}
	}
	if origin := uploadsCanonicalOrigin(app); origin != "" {
		return strings.TrimRight(origin, "/")
	}
	log.Printf("SECURITY: building a credential link (reset/verify) from the request Host %q - set BENMORE_PUBLIC_URL or seo.url so a host-header-poisoning attacker can't redirect the token", r.Host)
	return fmt.Sprintf("%s://%s", protoOf(r), r.Host)
}

// ===== Password Reset =====

// EnsurePasswordResetsTable creates the password reset tokens table.
func EnsurePasswordResetsTable(db *sql.DB) {
	db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_password_resets (
		token TEXT PRIMARY KEY,
		email TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		used INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	// Add type column to distinguish reset vs verify tokens (migration-safe)
	db.Exec("ALTER TABLE _benmore_password_resets ADD COLUMN type TEXT DEFAULT 'reset'")
	// Cleanup expired tokens
	db.Exec("DELETE FROM _benmore_password_resets WHERE expires_at < datetime('now')")
}

// hashResetToken returns the SHA-256 hex of a password-reset / email-verify
// token. Tokens are stored hashed (2026-06-11 audit) so a DB-read leak
// (backup, SQL console) can't expose live account-takeover links - same
// posture as API tokens. The raw token only ever exists inside the email.
func hashResetToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func handleForgotPassword(w http.ResponseWriter, r *http.Request, app *App) {
	mergeJSONBodyIntoForm(r)
	email := normalizeEmail(r.FormValue("email"))
	if email == "" {
		authRedirect(w, r, app.Paths.ForgotPassword, "Email is required")
		return
	}

	// Per-target cooldown: cap reset emails per address so an attacker can't
	// inbox-bomb a known user or flood _benmore_password_resets. Checked
	// before the existence lookup so the response timing/behavior is uniform
	// regardless of whether the account exists (no enumeration signal). The
	// always-success redirect below is unchanged.
	if !forgotPasswordLimiter.Allow("fp:" + strings.ToLower(email)) {
		http.Redirect(w, r, app.Paths.ForgotPassword+"?success="+url.QueryEscape("If that email exists, a reset link has been sent."), http.StatusSeeOther)
		return
	}

	// Always show success (don't leak whether email exists)
	// But only send email if account exists
	var count int
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_users WHERE email = ? COLLATE NOCASE", email).Scan(&count)
	if count > 0 {
		token := generateToken(32)
		expires := time.Now().Add(1 * time.Hour)
		app.DB.Exec("INSERT INTO _benmore_password_resets (token, email, expires_at, type) VALUES (?, ?, ?, 'reset')",
			hashResetToken(token), email, expires.UTC().Format(time.RFC3339))

		// Build reset URL - prefer configured SEO URL over r.Host to prevent header injection
		resetURL := fmt.Sprintf("%s%s?token=%s", securityLinkBaseURL(app, r), app.Paths.ResetPassword, token)

		siteName := "App"
		if app.Design != nil {
			if sn, ok := app.Design.SEO["site_name"]; ok && sn != "" {
				siteName = sn
			}
		}

		body := RenderBrandedEmail(
			AppEmailBrand(app, r),
			"Reset your password",
			fmt.Sprintf("Click the button below to set a new password for your %s account. This link expires in 1 hour.", html.EscapeString(siteName)),
			"Reset password",
			resetURL,
			"If you didn't request this, you can safely ignore this email - no changes will be made to your account.",
		)
		if err := SendEmail(app.Dir, email, "Reset your password · "+siteName, body); err != nil {
			log.Printf("auth: password-reset email failed (to=%s): %v", email, err)
		}
	}

	// Always show success (don't reveal whether email exists)
	http.Redirect(w, r, app.Paths.ForgotPassword+"?success="+url.QueryEscape("If that email exists, a reset link has been sent."), http.StatusSeeOther)
}

func handleResetPassword(w http.ResponseWriter, r *http.Request, app *App) {
	mergeJSONBodyIntoForm(r)
	token := r.FormValue("token")
	password := r.FormValue("password")
	confirm := r.FormValue("confirm")

	if token == "" {
		authRedirect(w, r, app.Paths.ResetPassword, "Invalid reset link")
		return
	}
	if password == "" {
		authRedirect(w, r, app.Paths.ResetPassword, "Password is required")
		return
	}
	if password != confirm {
		authRedirect(w, r, app.Paths.ResetPassword, "Passwords do not match")
		return
	}
	if msg := validatePasswordComplexity(password); msg != "" {
		authRedirect(w, r, app.Paths.ResetPassword, msg)
		return
	}

	// Validate token - only accept 'reset' type tokens (not 'verify').
	// Tokens are stored hashed; the IN(hash, raw) form keeps links that
	// were issued (plaintext) just before this deploy working through
	// their 1h TTL - safe to collapse to `token = ?` next release.
	var email string
	err := app.DB.QueryRow(
		"SELECT email FROM _benmore_password_resets WHERE token IN (?, ?) AND expires_at > datetime('now') AND used = 0 AND type = 'reset'",
		hashResetToken(token), token,
	).Scan(&email)
	if err != nil {
		authRedirect(w, r, app.Paths.ResetPassword, "Invalid or expired reset link")
		return
	}

	// Mark token as used atomically FIRST - prevents TOCTOU race on concurrent reset requests.
	// Only the winner of this atomic update proceeds to change the password.
	result, _ := app.DB.Exec("UPDATE _benmore_password_resets SET used = 1 WHERE token IN (?, ?) AND used = 0", hashResetToken(token), token)
	if affected, _ := result.RowsAffected(); affected == 0 {
		authRedirect(w, r, app.Paths.ResetPassword, "Reset link already used")
		return
	}

	// Update password (only reached by the single request that won the atomic check)
	hash, err := generateBcryptHash([]byte(password))
	if err != nil {
		authRedirect(w, r, app.Paths.ResetPassword, "Server error")
		return
	}
	app.DB.Exec("UPDATE _benmore_users SET password_hash = ? WHERE email = ? COLLATE NOCASE", string(hash), email)

	// Kill ALL existing sessions for this user - attacker sessions die here
	var userID int64
	app.DB.QueryRow("SELECT id FROM _benmore_users WHERE email = ? COLLATE NOCASE", email).Scan(&userID)
	if userID > 0 {
		app.DB.Exec("DELETE FROM _benmore_sessions WHERE user_id = ?", userID)
	}

	// Redirect to login with a success message the page can surface.
	http.Redirect(w, r, app.Paths.Login+"?success="+url.QueryEscape("Password updated. Sign in with your new password."), http.StatusSeeOther)
}

// handleTokenAuth exchanges email+password for a Bearer token (for native/API clients).
// POST /api/_auth/token with JSON body: {"email": "...", "password": "..."}
// Returns: {"token": "...", "user_id": N, "email": "..."}
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

func handleTokenAuth(w http.ResponseWriter, r *http.Request, app *App) {
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
	var hash, email string
	query := fmt.Sprintf("SELECT id, password_hash, COALESCE(email, '') FROM _benmore_users WHERE %s = ?", identifier)
	if identifier == "email" {
		query += " COLLATE NOCASE"
	}
	err := app.DB.QueryRow(query, body.Email).Scan(&userID, &hash, &email)
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

func handleVerifyEmail(w http.ResponseWriter, r *http.Request, app *App) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Redirect(w, r, app.Paths.Login, http.StatusSeeOther)
		return
	}

	// Validate token - only accept 'verify' type tokens (not 'reset').
	// Stored hashed; IN(hash, raw) covers links issued pre-deploy (1h TTL).
	var email string
	err := app.DB.QueryRow(
		"SELECT email FROM _benmore_password_resets WHERE token IN (?, ?) AND expires_at > datetime('now') AND used = 0 AND type = 'verify'",
		hashResetToken(token), token,
	).Scan(&email)
	if err != nil {
		http.Redirect(w, r, app.Paths.Login, http.StatusSeeOther)
		return
	}

	// Mark token as used atomically - prevents replay
	result, _ := app.DB.Exec("UPDATE _benmore_password_resets SET used = 1 WHERE token IN (?, ?) AND used = 0 AND type = 'verify'", hashResetToken(token), token)
	if affected, _ := result.RowsAffected(); affected == 0 {
		http.Redirect(w, r, app.Paths.Login, http.StatusSeeOther)
		return
	}

	// Mark user as verified
	app.DB.Exec("UPDATE _benmore_users SET verified = 1 WHERE email = ?", email)

	http.Redirect(w, r, app.Paths.Login, http.StatusSeeOther)
}

// ===== Session Helpers =====

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
			if strings.HasPrefix(token, "bmr_") {
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
			if !strings.HasPrefix(session.ID, "apitoken:") {
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

	// Apply role-based scopes: if session has no explicit scopes (cookie session)
	// and app has roles config, apply the UNION of every held role's scopes
	// (after inheritance expansion).
	//
	// SECURITY: if roles are configured but NONE of the user's roles are
	// defined, deny access (empty scopes that will be checked = denied on
	// first API call). Undefined roles must NOT get full access.
	if session.Scopes == "" && app.Roles != nil {
		held := session.Roles
		if len(held) == 0 {
			held = []string{session.Role}
		}
		roleScopes := app.Roles.ResolveScopesForRoles(held)
		if roleScopes != "" {
			session.Scopes = roleScopes
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

// maxPasswordLength is the hard limit on password input length.
// bcrypt silently truncates at 72 bytes - we reject well before that.
const maxPasswordLength = 128

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

// InjectCSRF adds a hidden CSRF field to all forms in HTML content.
func InjectCSRF(content string) string {
	token := generateCSRFToken()
	csrfField := fmt.Sprintf(`<input type="hidden" name="%s" value="%s">`, csrfTokenName, token)

	result := strings.Builder{}
	i := 0
	lower := strings.ToLower(content)
	for {
		idx := strings.Index(lower[i:], "<form")
		if idx < 0 {
			result.WriteString(content[i:])
			break
		}
		pos := i + idx
		closeIdx := strings.Index(content[pos:], ">")
		if closeIdx < 0 {
			result.WriteString(content[i:])
			break
		}
		endOfTag := pos + closeIdx + 1
		result.WriteString(content[i:endOfTag])
		result.WriteString(csrfField)
		i = endOfTag
	}
	return result.String()
}

// SecureCompare performs constant-time string comparison.
func SecureCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

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

// ===== Persistent API Tokens =====

// hashToken computes SHA-256 of a raw token for storage.
// The raw token is returned once on creation, never stored.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// GetSessionFromAPIToken resolves a Bearer token as a persistent API token.
// Returns nil if not found or expired.
func GetSessionFromAPIToken(db *sql.DB, rawToken string) *Session {
	tokenHash := hashToken(rawToken)

	var userID int64
	var scopes string
	var expiresAt sql.NullString
	err := db.QueryRow(
		"SELECT user_id, scopes, expires_at FROM _benmore_api_tokens WHERE token_hash = ?",
		tokenHash,
	).Scan(&userID, &scopes, &expiresAt)
	if err != nil {
		return nil
	}

	// Check expiry
	if expiresAt.Valid && expiresAt.String != "" {
		t, err := time.Parse(time.RFC3339, expiresAt.String)
		if err == nil && t.Before(time.Now()) {
			return nil // expired
		}
	}

	// Look up user details + deactivation status in one query
	var email, role string
	var deactivatedAt sql.NullString
	var verified int
	err = db.QueryRow("SELECT COALESCE(email, ''), COALESCE(role, 'user'), deactivated_at, COALESCE(verified, 0) FROM _benmore_users WHERE id = ?", userID).Scan(&email, &role, &deactivatedAt, &verified)
	if err != nil {
		return nil // user deleted
	}
	if deactivatedAt.Valid && deactivatedAt.String != "" {
		return nil // deactivated users blocked
	}

	// Update last_used_at (fire-and-forget)
	go db.Exec("UPDATE _benmore_api_tokens SET last_used_at = datetime('now') WHERE token_hash = ?", tokenHash)

	return &Session{
		ID:          fmt.Sprintf("apitoken:%s", tokenHash[:16]),
		UserID:      userID,
		Email:       email,
		GroupID:     "", // resolved lazily by getSession
		Role:        role,
		Scopes:      scopes,
		Verified:    verified == 1,
		GlobalAdmin: role == "admin" || UserHasGlobalAdminGrant(db, userID),
	}
}

// handleCreateAPIToken creates a persistent API token.
// POST /api/_auth/api-tokens {name, scopes, expires_in?}
func handleCreateAPIToken(w http.ResponseWriter, r *http.Request, app *App) {
	session := getSession(app, r)
	if session == nil {
		httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}

	var body struct {
		Name      string `json:"name"`
		Scopes    string `json:"scopes"`
		ExpiresIn string `json:"expires_in"` // "30d", "90d", "1y", "" for no expiry
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request"})
		return
	}
	if body.Name == "" {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "name required"})
		return
	}
	if body.Scopes == "" {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "scopes required (use '*' for full access)"})
		return
	}
	if err := validateScopes(body.Scopes); err != nil {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	// Generate raw token with identifiable prefix
	rawToken := "bmr_" + generateToken(32)
	tokenHash := hashToken(rawToken)

	// Parse expiry
	var expiresAt *string
	if body.ExpiresIn != "" {
		dur := parseTokenExpiry(body.ExpiresIn)
		if dur == 0 {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid expires_in (use 30d, 90d, 1y)"})
			return
		}
		t := time.Now().Add(dur).UTC().Format(time.RFC3339)
		expiresAt = &t
	}

	_, err := app.DB.Exec(
		"INSERT INTO _benmore_api_tokens (user_id, name, token_hash, scopes, expires_at) VALUES (?, ?, ?, ?, ?)",
		session.UserID, body.Name, tokenHash, body.Scopes, expiresAt,
	)
	if err != nil {
		httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to create token"})
		return
	}

	// Return raw token ONCE - it's never stored or retrievable again
	httpJSON(w, http.StatusOK, map[string]any{
		"token":  rawToken,
		"name":   body.Name,
		"scopes": body.Scopes,
	})
}

// handleListAPITokens lists the authenticated user's API tokens.
// GET /api/_auth/api-tokens
func handleListAPITokens(w http.ResponseWriter, r *http.Request, app *App) {
	session := getSession(app, r)
	if session == nil {
		httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}

	rows, err := QueryRows(app.DB,
		"SELECT id, name, scopes, last_used_at, expires_at, created_at FROM _benmore_api_tokens WHERE user_id = ? ORDER BY created_at DESC",
		session.UserID,
	)
	if err != nil {
		httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "query failed"})
		return
	}

	httpJSON(w, http.StatusOK, map[string]any{"tokens": rows})
}

// handleRevokeAPIToken deletes a persistent API token.
// DELETE /api/_auth/api-tokens/{id}
func handleRevokeAPIToken(w http.ResponseWriter, r *http.Request, app *App) {
	session := getSession(app, r)
	if session == nil {
		httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}
	if !isBearerAuth(r) && !validateCSRF(r) {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
		return
	}

	id := r.PathValue("id")
	if id == "" {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "token id required"})
		return
	}

	// SECURITY: users can only revoke their own tokens
	result, err := app.DB.Exec(
		"DELETE FROM _benmore_api_tokens WHERE id = ? AND user_id = ?",
		id, session.UserID,
	)
	if err != nil {
		httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "revoke failed"})
		return
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		httpJSON(w, http.StatusNotFound, map[string]any{"error": "token not found"})
		return
	}

	httpJSON(w, http.StatusOK, map[string]any{"status": "revoked"})
}

// parseTokenExpiry parses "30d", "90d", "1y" into a time.Duration.
func parseTokenExpiry(s string) time.Duration {
	s = strings.TrimSpace(strings.ToLower(s))
	if strings.HasSuffix(s, "d") {
		var days int
		if _, err := fmt.Sscanf(s, "%dd", &days); err == nil && days > 0 && days <= 365 {
			return time.Duration(days) * 24 * time.Hour
		}
	}
	if strings.HasSuffix(s, "y") {
		var years int
		if _, err := fmt.Sscanf(s, "%dy", &years); err == nil && years > 0 && years <= 5 {
			return time.Duration(years) * 365 * 24 * time.Hour
		}
	}
	return 0
}

// Ensure imports are used
var _ = sql.ErrNoRows
