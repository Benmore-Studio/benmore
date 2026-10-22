//go:build !cli

package main

// Session persistence, request identity resolution, and tenant role scopes.
// Auth routes and process-wide secret initialization remain in auth.go.

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// Session cookie names. Over HTTPS the cookie carries the __Host- prefix, so
// a browser keeps it only host-only, Secure and on Path=/: no other app or
// edge on a sibling subdomain can set or shadow it with a Domain-scoped
// cookie (the cookie-tossing path to session fixation). Plain-HTTP
// development keeps the unprefixed name, which HTTPS requests ignore.
const (
	sessionCookieName    = "__Host-benmore_session"
	devSessionCookieName = "_benmore_session"
)

// sessionCookieNameFor is the session cookie name for a Secure flag.
func sessionCookieNameFor(secure bool) string {
	if secure {
		return sessionCookieName
	}
	return devSessionCookieName
}

// requestSessionCookie returns the session cookie a request carries. The
// unprefixed name counts only on a plain-HTTP request: over HTTPS it is
// exactly what a sibling subdomain could plant.
func requestSessionCookie(r *http.Request) (*http.Cookie, error) {
	if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
		return c, nil
	}
	if protoOf(r) != "https" {
		return r.Cookie(devSessionCookieName)
	}
	return nil, http.ErrNoCookie
}

// clearSessionCookies expires the session cookie under both names.
func clearSessionCookies(w http.ResponseWriter, devMode bool) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	http.SetCookie(w, &http.Cookie{Name: devSessionCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: !devMode, SameSite: http.SameSiteLaxMode})
}

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
	// The admin behind an impersonation session, recorded at start so the
	// audit trail keeps naming them after the originating session ends.
	db.Exec("ALTER TABLE _benmore_sessions ADD COLUMN impersonator_user_id INTEGER DEFAULT 0")
	db.Exec("ALTER TABLE _benmore_sessions ADD COLUMN impersonator_email TEXT DEFAULT ''")
	// Add ip + user_agent columns so the Sessions tab on /profile can
	// show a real device label instead of "unknown ip". Captured by
	// AttachSessionContext right after CreateSession.
	db.Exec("ALTER TABLE _benmore_sessions ADD COLUMN ip TEXT DEFAULT ''")
	db.Exec("ALTER TABLE _benmore_sessions ADD COLUMN user_agent TEXT DEFAULT ''")
	// acting_as_group: admin step-in target. While non-empty, the
	// session's effective tenant is this value (see Session.EffectiveGroupID
	// and IsAdminBypass). Cleared on POST /api/_auth/act_as with no body.
	db.Exec("ALTER TABLE _benmore_sessions ADD COLUMN acting_as_group TEXT DEFAULT ''")
	// login_at: unix time of the person's own interactive sign-in that
	// created this session (createSignInSession). 0 - every row from before
	// the column, and every session minted any other way - never counts as a
	// recent sign-in (recentDirectSignIn).
	db.Exec("ALTER TABLE _benmore_sessions ADD COLUMN login_at INTEGER NOT NULL DEFAULT 0")
	// Every credential revocation (password change/reset, claim, purge,
	// email change, session list) filters by user_id; without an index each
	// was a full scan of every session in the app.
	db.Exec("CREATE INDEX IF NOT EXISTS idx_benmore_sessions_user ON _benmore_sessions(user_id)")
	// Expiry is compared as datetime(expires_at) on purpose (rows hold both
	// RFC3339 and SQLite text forms, which don't compare as plain text), so
	// the cleanup sweeps index that expression. datetime() of a column is
	// deterministic, which SQLite requires of an index expression.
	db.Exec("CREATE INDEX IF NOT EXISTS idx_benmore_sessions_expiry ON _benmore_sessions(datetime(expires_at))")
	// Cleanup expired on startup
	db.Exec("DELETE FROM _benmore_sessions WHERE datetime(expires_at) < datetime('now')")
	// Rows written before session ids were hashed hold the credential itself.
	// Rekey them now so the table never keeps a usable session id at rest.
	if err := migrateLegacySessionIDs(db); err != nil {
		log.Printf("sessions: hashing legacy session ids failed (they are rekeyed on next use): %v", err)
	}
}

// AttachSessionContext records the originating IP + user-agent on a
// session row. Called right after CreateSession, with the token it
// returned, from any handler that has the *http.Request available.
// Best-effort - failures are logged and ignored (the session is already
// valid).
func AttachSessionContext(db *sql.DB, sessionToken string, r *http.Request) {
	if sessionToken == "" || r == nil {
		return
	}
	ua := r.UserAgent()
	if len(ua) > 240 {
		ua = ua[:240]
	}
	if _, err := db.Exec(
		"UPDATE _benmore_sessions SET ip = ?, user_agent = ? WHERE id = ?",
		clientIP(r), ua, sessionStorageKey(sessionToken),
	); err != nil {
		log.Printf("session context update failed: %v", err)
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
	role, _ := resolveMembershipRoleWith(db, group, email, effectiveGroupID, "")
	return role
}

// resolveMembershipRoleWith looks the member up by email, so it matches only a
// membership column that holds addresses. A table keyed by user id is matched
// through resolveMembershipRoleForSessionWith first (applySessionRoleScopesWith).
func resolveMembershipRoleWith(db rowQuerier, group *GroupConfig, email, effectiveGroupID, schema string) (string, error) {
	return resolveMembershipRoleForValueWith(db, group, email, email, effectiveGroupID, schema)
}

func resolveMembershipRoleForSessionWith(db rowQuerier, group *GroupConfig, session *Session, effectiveGroupID, schema string) (string, error) {
	if session == nil {
		return "", nil
	}
	member, ok := groupMemberValue(group, session)
	if !ok {
		return "", nil
	}
	return resolveMembershipRoleForValueWith(db, group, member, sessionGrantEmail(session), effectiveGroupID, schema)
}

func resolveMembershipRoleForValueWith(db rowQuerier, group *GroupConfig, member any, email, effectiveGroupID, schema string) (string, error) {
	if group == nil || group.Table == "" || group.Key == "" || group.UserField == "" || group.RoleField == "" || effectiveGroupID == "" {
		return "", nil
	}
	if schema == "main" && (!membershipIdentRe.MatchString(group.Key) || !membershipIdentRe.MatchString(group.UserField) || !membershipIdentRe.MatchString(group.RoleField)) {
		return "", fmt.Errorf("invalid main membership columns")
	}
	hasCol, metadataErr := dbColumnCheckerWith(db, group.Table, schema)
	conds := membershipLiveConds(group, group.Table, "", hasCol)
	// Explicit-schema connector authority is strict; the ordinary wrapper
	// retains its established optional-metadata fallback.
	if err := metadataErr(); err != nil && schema != "" {
		return "", err
	}
	// from is the membership table as written after FROM; name is what its
	// columns are qualified with (the bare table name in both cases).
	from, name := quoteIdent(group.Table), group.Table
	if schema == "main" {
		var ok bool
		from, name, ok = mainAuthorityTable(group.Table)
		if !ok {
			return "", fmt.Errorf("invalid main membership table")
		}
	} else if schema != "" {
		return "", fmt.Errorf("unsupported membership authority schema")
	}
	var role sql.NullString
	query := fmt.Sprintf("SELECT %s FROM %s WHERE %s = ? AND %s = ?%s",
		quoteColumn(name, group.RoleField), from, quoteColumn(name, group.UserField), quoteColumn(name, group.Key),
		conds)
	args := []any{member, effectiveGroupID}
	if _, byAddress := member.(string); byAddress || emailKeyedColumn(group.UserField) {
		// A membership matched by address belongs to whoever proved the
		// address, whatever the column holding it is called.
		query += " AND " + verifiedAccountEmailSQLForSchema(schema)
		args = append(args, email)
	}
	if err := db.QueryRow(query+" LIMIT 1", args...).Scan(&role); err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", err
	}
	if !role.Valid {
		return "", nil
	}
	return strings.TrimSpace(role.String), nil
}

// mainAuthorityTable returns the membership table pinned to the main schema,
// as written after FROM, and its bare name (what its columns are qualified
// with). ok=false for anything but a plain name, optionally written `main.x`.
func mainAuthorityTable(table string) (from, name string, ok bool) {
	prefix, name, qualified := strings.Cut(table, ".")
	if qualified {
		if !strings.EqualFold(prefix, "main") {
			return "", "", false
		}
	} else {
		name = prefix
	}
	if !membershipIdentRe.MatchString(name) {
		return "", "", false
	}
	return "main." + quoteIdent(name), name, true
}

// ResolveGroupID looks up the user's organization from the configured
// membership table. v2.5.10: returns string (was int64) so UUID/slug/
// opaque-ID tenant keys work natively. Empty string means "no group".
func ResolveGroupID(db *sql.DB, group *GroupConfig, email string) string {
	if group == nil || group.Table == "" || group.Key == "" || group.UserField == "" {
		return ""
	}
	// A membership table keyed by user id (a user_field that isn't an email
	// column: groupMemberValue, groups_bootstrap) names its members by
	// _benmore_users.id. Comparing that column only with the email matched
	// nothing, so such tenants never resolved. The id is the account whose
	// email is exactly this one; a case variant is another account.
	if !emailKeyedColumn(group.UserField) && email != "" {
		var id int64
		if db.QueryRow("SELECT id FROM _benmore_users WHERE email = ?", email).Scan(&id) == nil {
			if gid := resolveGroupIDFor(db, group, id, email); gid != "" {
				return gid
			}
		}
	}
	// By address: an email-keyed table, and a column that holds addresses
	// under another name (which has always resolved this way).
	if !membershipAddressMatch(group, email) {
		return ""
	}
	return resolveGroupIDFor(db, group, email, email)
}

// membershipAddressMatch reports whether the membership column may be
// compared with email: always for an email column, and for any other column
// only when the value is an address. An id column must never be compared
// with a stray non-address value ("7" equals user id 7 under SQLite's
// column affinity).
func membershipAddressMatch(group *GroupConfig, email string) bool {
	return group != nil && (emailKeyedColumn(group.UserField) || strings.Contains(email, "@"))
}

// resolveGroupIDFor is ResolveGroupID for a known member value: the verified
// email for an email-keyed membership table, the user id for an id-keyed one
// (groupMemberValue). email is the account's address, used only for the
// verified-address check of an email-keyed row.
func resolveGroupIDFor(db *sql.DB, group *GroupConfig, member any, email string) string {
	if group == nil || group.Table == "" || group.Key == "" || group.UserField == "" {
		return ""
	}
	var groupID sql.NullString
	// Only a live row (not soft-deleted, active per groups.active_field)
	// places the user in a tenant.
	key := quoteColumn(group.Table, group.Key)
	query := fmt.Sprintf("SELECT %s FROM %s WHERE %s = ? AND %s IS NOT NULL%s",
		key, quoteIdent(group.Table), quoteColumn(group.Table, group.UserField), key,
		membershipLiveConds(group, group.Table, "", dbColumnChecker(db, group.Table)))
	args := []any{member}
	if _, byAddress := member.(string); byAddress || emailKeyedColumn(group.UserField) {
		// A membership row addressed to an email is an invitation to that
		// address: it resolves only for an account that has verified it,
		// whatever the column holding the address is called.
		query += " AND " + verifiedAccountEmailSQL
		args = append(args, email)
	}
	// ORDER BY rowid: a user with several live memberships always lands
	// in the same (oldest) tenant, not whichever row the planner meets first.
	err := db.QueryRow(query+" ORDER BY rowid LIMIT 1", args...).Scan(&groupID)
	if err != nil && err != sql.ErrNoRows && !tableHasRowID(db, group.Table) {
		// A view or WITHOUT ROWID membership table has no rowid: order by
		// the tenant key (still deterministic) instead of resolving every
		// member to no tenant.
		err = db.QueryRow(query+" ORDER BY "+key+" LIMIT 1", args...).Scan(&groupID)
	}
	if err != nil {
		return ""
	}
	if !groupID.Valid {
		return ""
	}
	return groupID.String
}

// tableHasRowID reports false only for a table SQLite positively lists as a
// view or a WITHOUT ROWID table; any lookup failure counts as having a rowid.
func tableHasRowID(db *sql.DB, table string) bool {
	var kind string
	var withoutRowID int
	if err := db.QueryRow("SELECT type, wr FROM pragma_table_list WHERE name = ? COLLATE NOCASE LIMIT 1", table).Scan(&kind, &withoutRowID); err != nil {
		return true
	}
	return kind != "view" && withoutRowID == 0
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

// CreateSession creates a persistent session in SQLite and returns its
// token: the credential for the cookie or Bearer header. The row stores
// only sessionStorageKey(token). v2.5.10: groupID is now string (was
// int64). SQLite's group_id column has INTEGER affinity but dynamic
// typing accepts the string; UUID/slug tenant keys round-trip correctly.
func CreateSession(db *sql.DB, userID int64, email string, groupID string, duration time.Duration, scopes ...string) string {
	token, err := createSessionWith(db, userID, email, groupID, duration, scopes...)
	if err != nil {
		log.Printf("ERROR creating session: %s", err)
		return ""
	}
	return token
}

func createSessionWith(db interface {
	Exec(string, ...any) (sql.Result, error)
}, userID int64, email string, groupID string, duration time.Duration, scopes ...string) (string, error) {
	token := generateToken(32)
	if duration <= 0 {
		duration = defaultSessionDuration
	}
	expires := time.Now().Add(duration)
	scopeStr := ""
	if len(scopes) > 0 {
		scopeStr = scopes[0]
	}
	if _, err := db.Exec("INSERT INTO _benmore_sessions (id, user_id, email, group_id, scopes, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
		sessionStorageKey(token), userID, email, groupID, scopeStr, expires.UTC().Format(time.RFC3339)); err != nil {
		return "", err
	}
	return token, nil
}

// recentSignInWindow is how long a direct sign-in stands in for re-entering
// the password (recentDirectSignIn).
const recentSignInWindow = 10 * time.Minute

// createSignInSession is CreateSession for the person's own interactive
// sign-in: a password, OAuth or passkey sign-in, or the code or second-factor
// step that completes one. The row records when it happened (login_at), so a
// sensitive change made right afterwards can take the sign-in as proof of the
// account. Sessions minted any other way (impersonation, delegated tooling,
// embeds, the Bearer token exchange) keep login_at 0 and never count. If the
// time cannot be recorded the session still works; it just isn't recent.
func createSignInSession(db *sql.DB, userID int64, email string, groupID string, duration time.Duration) string {
	token := CreateSession(db, userID, email, groupID, duration)
	if token != "" {
		if _, err := db.Exec("UPDATE _benmore_sessions SET login_at = ? WHERE id = ?", time.Now().Unix(), sessionStorageKey(token)); err != nil {
			log.Printf("session sign-in time not recorded: %v", err)
		}
	}
	return token
}

// createSignInSessionTx lets enrollment activate its factor and issue the
// resulting credential atomically. Failure leaves neither change committed.
func createSignInSessionTx(tx *sql.Tx, userID int64, email, groupID string, duration time.Duration) (string, error) {
	token, err := createSessionWith(tx, userID, email, groupID, duration)
	if err != nil {
		return "", err
	}
	if _, err := tx.Exec("UPDATE _benmore_sessions SET login_at = ? WHERE id = ?", time.Now().Unix(), sessionStorageKey(token)); err != nil {
		return "", err
	}
	return token, nil
}

// recentDirectSignIn reports whether the request's own browser session comes
// from a direct sign-in (createSignInSession) made within recentSignInWindow:
// the session cookie, not a Bearer header, and a row that is not
// impersonation, act-as or scoped. Older sign-ins, Bearer-presented tokens,
// API tokens, edge identities and sessions minted outside a sign-in are false.
func recentDirectSignIn(app *App, r *http.Request, sess *Session) bool {
	if app == nil || app.DB == nil || r == nil || sess == nil || sess.UserID <= 0 || !directLoginSession(app, sess) {
		return false
	}
	c, err := requestSessionCookie(r)
	if err != nil || c.Value == "" {
		return false
	}
	if key, ok := presentedSessionKey(c.Value); !ok || key != sess.ID {
		return false
	}
	var loginAt int64
	if err := app.DB.QueryRow(`SELECT COALESCE(login_at, 0) FROM _benmore_sessions
		WHERE id = ? AND user_id = ? AND COALESCE(is_impersonation, 0) = 0
		AND COALESCE(acting_as_group, '') = '' AND COALESCE(scopes, '') IN ('', '*')`,
		sess.ID, sess.UserID).Scan(&loginAt); err != nil || loginAt <= 0 {
		return false
	}
	now := time.Now().Unix()
	return loginAt <= now+60 && now-loginAt <= int64(recentSignInWindow/time.Second)
}

// createDelegatedSession mints a session for platform tooling acting as an
// app user (probe_route `as`, browser_check `as`). Pages and APIs resolve it
// like a login, but the row is stored as impersonation with no impersonator,
// so every direct-login gate refuses it: connector consent and approval, API
// token minting, scheduled flows, data export and password/account changes.
// The user never signed in; an agent must not mint credentials as them.
func createDelegatedSession(db *sql.DB, userID int64, email string, groupID string, duration time.Duration) string {
	token := generateToken(32)
	if _, err := db.Exec("INSERT INTO _benmore_sessions (id, user_id, email, group_id, scopes, expires_at, is_impersonation) VALUES (?, ?, ?, ?, '', ?, 1)",
		sessionStorageKey(token), userID, email, groupID, time.Now().Add(duration).UTC().Format(time.RFC3339)); err != nil {
		log.Printf("ERROR creating delegated session: %s", err)
		return ""
	}
	return token
}

// GetSessionFromDB resolves a session token a client presented (cookie or
// Bearer). The returned Session's ID is the stored key. A row still stored
// under its raw id is found too, and rekeyed to the hashed form.
func GetSessionFromDB(db *sql.DB, token string) *Session {
	key, ok := presentedSessionKey(token)
	if !ok {
		return nil
	}
	s := loadStoredSession(db, key, token)
	if s != nil && s.ID != key {
		s.ID = rekeyLegacySession(db, s.ID, key)
	}
	return s
}

// getSessionByStoredID resolves a session by the id recorded in the database
// (an impersonation row's impersonator_session_id). Never pass it a value a
// client supplied: a stored id is not a credential.
func getSessionByStoredID(db *sql.DB, storedID string) *Session {
	if storedID == "" {
		return nil
	}
	return loadStoredSession(db, storedID)
}

// loadStoredSession loads the live session whose row id is one of ids.
// Joins _benmore_users in a single query to get role, deactivated_at, and verified
// without extra round-trips.
func loadStoredSession(db *sql.DB, ids ...string) *Session {
	return loadStoredSessionWith(db, false, ids...)
}

func loadStoredSessionWith(db mutationQuerier, strict bool, ids ...string) *Session {
	s, _ := loadStoredSessionChecked(db, strict, ids...)
	return s
}

// loadStoredSessionChecked is loadStoredSessionWith that tells "no such live
// session" (nil, nil: absent, expired, deactivated, password change pending)
// from a failed read (nil, err: SQLITE_BUSY, I/O, cancellation). A caller that
// grants or denies authority must not read the second as the first.
func loadStoredSessionChecked(db mutationQuerier, strict bool, ids ...string) (*Session, error) {
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	var storedID string
	var userID int64
	var email string
	// group_id may be either an INTEGER (legacy) or TEXT (UUID tenants
	// post v2.5.10). sql.NullString accepts both - SQLite's text
	// affinity coerces INT values to their decimal string form on read.
	var groupID sql.NullString
	var scopes string
	var role string
	var deactivatedAt sql.NullString
	var verified, grandfathered int
	var actingAs sql.NullString
	var impersonatorID int64
	var impersonatorEmail string
	prefix := ""
	if strict {
		prefix = "main."
	}
	// The email is the account's CURRENT one (u.email), never the copy the
	// session row took at sign-in: tenant membership, member-of rules, shares
	// and invites resolve by it, so after an operator changes an account's
	// address its open sessions must stop answering for the old one.
	err := db.QueryRow(`
  SELECT s.id, s.user_id, COALESCE(u.email, ''), COALESCE(s.group_id, ''), COALESCE(s.scopes, ''),
		       COALESCE(u.role, 'user'), u.deactivated_at, COALESCE(u.verified, 0), COALESCE(u.email_grandfathered, 0),
		       COALESCE(s.acting_as_group, ''),
		       CASE WHEN COALESCE(s.is_impersonation, 0) = 1 THEN COALESCE(s.impersonator_user_id, 0) ELSE 0 END,
		       CASE WHEN COALESCE(s.is_impersonation, 0) = 1 THEN COALESCE(s.impersonator_email, '') ELSE '' END
		FROM `+prefix+`_benmore_sessions s
  JOIN `+prefix+`_benmore_users u ON u.id = s.user_id
		WHERE s.id IN (?`+strings.Repeat(", ?", len(ids)-1)+`) AND datetime(s.expires_at) > datetime('now')
		  AND COALESCE(u.password_change_required, 0) = 0`,
		args...,
	).Scan(&storedID, &userID, &email, &groupID, &scopes, &role, &deactivatedAt, &verified, &grandfathered, &actingAs, &impersonatorID, &impersonatorEmail)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read session: %w", err)
	}
	// Block deactivated users at session resolution - no further processing
	if deactivatedAt.Valid && deactivatedAt.String != "" {
		return nil, nil
	}
	// A support impersonation session acts on the authority of the admin who
	// started it. It is a row under the TARGET's user id, so the checks above
	// say nothing about that admin: one who was demoted, deactivated or
	// deleted mid-session kept acting as the customer until the hour ran
	// out. The session resolves only while its admin is still one.
	if impersonatorID != 0 {
		live, err := impersonatorStillAdmin(db, impersonatorID, strict)
		if err != nil && strict {
			return nil, fmt.Errorf("read session impersonator: %w", err)
		}
		if !live {
			return nil, nil
		}
	}
	gid := ""
	if groupID.Valid && groupID.String != "0" {
		gid = groupID.String
	}
	s := &Session{ID: storedID, UserID: userID, Email: email, GroupID: gid, Role: role, Scopes: scopes, CredentialScopes: scopes}
	s.Verified = verified == 1
	s.EmailGrandfathered = grandfathered == 1
	s.ImpersonatorUserID, s.ImpersonatorEmail = impersonatorID, impersonatorEmail
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
	var roleErr error
	schema := ""
	if strict {
		schema = "main"
	}
	// GlobalAdmin (cross-tenant bypass eligibility) comes ONLY from the
	// primary role column or a NULL-group admin grant - never from a
	// group-scoped grant or a (client-writable) membership role. Resolved
	// before the roles: the effective group they load for depends on it.
	s.GlobalAdmin = role == "admin"
	if !s.GlobalAdmin && userID != 0 {
		var grantErr error
		s.GlobalAdmin, grantErr = userHasGlobalAdminGrantWithSchema(db, userID, schema)
		if strict && grantErr != nil {
			return nil, fmt.Errorf("read session admin grants: %w", grantErr)
		}
	}
	// EffectiveGroupID honors a step-in only for an admin (types.go), which is
	// why the admin standing is resolved above: the roles load for the
	// effective group.
	s.Roles, roleErr = loadSessionRolesWithSchema(db, userID, role, s.EffectiveGroupID(), schema)
	if strict && roleErr != nil {
		return nil, fmt.Errorf("read session roles: %w", roleErr)
	}
	return s, nil
}

// impersonatorStillAdmin reports whether the admin behind a support session
// is still an active admin: present, not deactivated, not held at a temporary
// password, and admin by the role column or a global grant (IsAdmin's rule).
func impersonatorStillAdmin(db mutationQuerier, adminID int64, strict bool) (bool, error) {
	prefix, schema := "", ""
	if strict {
		prefix, schema = "main.", "main"
	}
	var role string
	err := db.QueryRow(`SELECT COALESCE(role, 'user') FROM `+prefix+`_benmore_users
		WHERE id = ? AND COALESCE(deactivated_at, '') = '' AND COALESCE(password_change_required, 0) = 0`, adminID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if role == "admin" {
		return true, nil
	}
	return userHasGlobalAdminGrantWithSchema(db, adminID, schema)
}

// DeleteSessionFromDB removes the session a token authenticates (logout,
// cleanup of a minted session), whether its row is hashed or legacy.
func DeleteSessionFromDB(db *sql.DB, token string) {
	key, ok := presentedSessionKey(token)
	if !ok {
		return
	}
	if _, err := db.Exec("DELETE FROM _benmore_sessions WHERE id IN (?, ?)", key, token); err != nil {
		log.Printf("ERROR deleting session: %s", err)
	}
}

// CleanExpiredSessions removes expired sessions periodically.
func CleanExpiredSessions(app *App) {
	if app == nil || app.DB == nil {
		return
	}
	stop := app.workerStopGeneration()
	safeGo("auth.cleanExpiredSessions", func() {
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
		Name:     sessionCookieNameFor(!devMode),
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
	if actor, private := appMCPPrivateSession(app, r); private {
		return actor
	}
	// Answer repeat lookups within one request from its cache
	// (auth_session_cache.go); never shared across requests.
	if holder := requestSessionHolderFor(r); holder != nil {
		if cred, ok := requestSessionCredential(r); ok {
			now := time.Now()
			if s, hit := holder.get(app, cred, now); hit {
				return s
			}
			s := resolveRequestSession(app, r)
			holder.put(app, cred, s, now)
			return s
		}
	}
	return resolveRequestSession(app, r)
}

// resolveRequestSession resolves the request's identity from the database:
// cookie, then Bearer session or API token, then the edge bridge.
func resolveRequestSession(app *App, r *http.Request) *Session {
	var session *Session

	// 1. Cookie (web clients) - always a session ID, never scoped
	if cookie, err := requestSessionCookie(r); err == nil && cookie.Value != "" {
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
				session.CredentialScopes = session.Scopes
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

	// The tenant cached on a session row holds only while the membership
	// behind it is live: removed, soft-deleted or deactivated members (and
	// unverified holders of an email-keyed membership) lose it on their
	// next request instead of keeping it for the session's lifetime. The
	// lazy resolution below then picks another live membership, if any.
	// Admins keep the tenant they switched into.
	if session.HasGroup() && app.Group != nil && app.Group.Table != "" && app.Group.UserField != "" &&
		!session.IsAdmin() && !groupMembershipLive(app.DB, app.Group, session, session.GroupID) {
		session.GroupID = ""
		if !strings.HasPrefix(session.ID, "apitoken:") && !strings.HasPrefix(session.ID, "edge:") {
			app.DB.Exec("UPDATE _benmore_sessions SET group_id = '' WHERE id = ?", session.ID)
		}
		session.Roles = LoadSessionRoles(app.DB, session.UserID, session.Role, session.EffectiveGroupID())
	}

	// Lazy-resolve org_id: if session has no org but app has org config,
	// re-check (handles signup → onboarding where user_roles is created after session).
	// An email-keyed membership counts only once this session's own account
	// has proven the address (groupMemberValue), the rule the revalidation
	// above applies: ResolveGroupID asks whether SOME account with the email
	// is verified, which a case-variant duplicate account also satisfies.
	if !session.HasGroup() && app.Group != nil && sessionMayHoldGroupMembership(app.Group, session) {
		// An id-keyed membership table matches this session's own user id;
		// otherwise (and for a column that holds addresses under another
		// name) the account's email, as before.
		resolved := ""
		if !emailKeyedColumn(app.Group.UserField) {
			resolved = resolveGroupIDFor(app.DB, app.Group, session.UserID, session.Email)
		}
		// The address comparison needs this session's own account to have
		// proven the address (sessionGrantEmail), as for an email column.
		if resolved == "" && membershipAddressMatch(app.Group, session.Email) && sessionGrantEmail(session) != "" {
			resolved = resolveGroupIDFor(app.DB, app.Group, session.Email, session.Email)
		}
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

// sessionMayHoldGroupMembership reports whether session can hold a groups:
// membership at all: always for an id-keyed table, and for an email-keyed
// one only once the account verified (or was grandfathered on) the address.
func sessionMayHoldGroupMembership(group *GroupConfig, session *Session) bool {
	_, ok := groupMemberValue(group, session)
	return ok
}

// Shared by interactive sessions and durable scheduled-task identities.
func applySessionRoleScopes(app *App, session *Session) *Session {
	session, _ = applySessionRoleScopesWith(app, app.DB, session, "")
	return session
}

func applySessionRoleScopesWith(app *App, db rowQuerier, session *Session, schema string) (*Session, error) {
	var roleErr error
	// Tenant role from the membership table (v2.7.164): when the
	// developer declares `groups.role_field`, the member's in-tenant
	// role (e.g. member_role on company_members) joins session.Roles
	// for the EFFECTIVE group, so `role:company_admin` access modes
	// enforce against the membership table directly. Runs BEFORE the
	// scope union below so a `roles:` mapping for the tenant role also
	// contributes its scopes.
	if app.Group != nil && app.Group.RoleField != "" && session.EffectiveHasGroup() {
		var mr string
		var err error
		if schema == "main" {
			mr, err = resolveMembershipRoleForSessionWith(db, app.Group, session, session.EffectiveGroupID(), schema)
		} else {
			// An id-keyed membership row names the user id, not the email:
			// looked up only by email it never matched, so the tenant role of
			// an id-keyed app was never loaded here. A column that holds
			// addresses under another name keeps matching by email.
			if !emailKeyedColumn(app.Group.UserField) {
				mr, err = resolveMembershipRoleForSessionWith(db, app.Group, session, session.EffectiveGroupID(), schema)
			}
			if mr == "" && err == nil && membershipAddressMatch(app.Group, session.Email) &&
				(emailKeyedColumn(app.Group.UserField) || sessionGrantEmail(session) != "") {
				mr, err = resolveMembershipRoleWith(db, app.Group, session.Email, session.EffectiveGroupID(), schema)
			}
		}
		roleErr = err
		if mr != "" {
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
		session.accessTables = app.Roles.accessTables
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

	return session, roleErr
}
