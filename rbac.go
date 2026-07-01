//go:build !cli

package main

// rbac.go - multi-role RBAC, v2.7.54+.
//
// Replaces the historical "one role per user" model (the `role` column
// on `_benmore_users`) with a join table that lets a user hold ANY
// number of roles simultaneously. Roles are still declared in app.yaml
// under the `roles:` section; the new `inherits:` field on each role
// def lets one role pull in another's scopes transitively.
//
// Wire-up:
//   - EnsureUserRolesTable creates _benmore_user_roles + a cursor
//     for the background expiry sweep.
//   - LoadSessionRoles is called from GetSessionFromDB to populate
//     session.Roles + session.Permissions.
//   - access.Allowed extends `role:X` to accept comma-separated
//     "any-of" lists and adds `perm:<scope>` as a permission-level
//     mode that checks session.Permissions / Scopes.
//   - StartRoleExpirySweeper runs a per-app background goroutine
//     that deletes expired assignments (and audits the eviction).
//
// Endpoints (RegisterRoleRoutes):
//   GET    /api/_auth/users/{id}/roles
//   POST   /api/_auth/users/{id}/roles      {role, expires_at?}
//   PATCH  /api/_auth/users/{id}/roles/{role}   {expires_at?}
//   DELETE /api/_auth/users/{id}/roles/{role}
//   GET    /api/_auth/roles                 - lists configured roles + effective scopes
//
// All grant / revoke / expiry events are logged via LogAudit. Only
// admins can manage assignments. Self-revoke of one's own primary role
// is rejected (would lock the user out instantly).

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// EnsureUserRolesTable creates the join table that backs multi-role
// assignment. v2.7.59+ supports tenant-scoped grants via the optional
// `group_id` column:
//
//	group_id IS NULL  → role applies globally (every group context)
//	group_id = 'X'    → role applies only when the session's effective
//	                    group is X (native group OR act-as target)
//
// Uniqueness: a user can hold each (role, group_id) pair at most once.
// The classic global form ({user 3, 'editor', NULL}) is allowed
// alongside group-scoped forms ({user 3, 'editor', '1'}). Because
// SQLite PRIMARY KEY treats each NULL as distinct, we enforce
// uniqueness via a UNIQUE INDEX that normalises NULL → ” for the
// comparison.
//
// Migration: an older table without the group_id column is migrated
// in place via the standard SQLite recreate-and-rename dance (CREATE
// new, INSERT … SELECT, DROP old, RENAME). Existing rows are
// preserved with group_id = NULL (global), which matches the
// pre-v2.7.59 semantics - no app's grants change meaning during the
// upgrade.
func EnsureUserRolesTable(db *sql.DB) error {
	// 1. First-time install: create the new-shape table from scratch.
	//    `CREATE TABLE IF NOT EXISTS` is a no-op when the table already
	//    exists, so this path is safe even when migrating an older
	//    table - the migration block below picks up that case.
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS _benmore_user_roles (
			user_id    INTEGER NOT NULL,
			role       TEXT    NOT NULL,
			group_id   TEXT,
			granted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			granted_by INTEGER,
			expires_at DATETIME
		)`)
	if err != nil {
		return err
	}
	// 2. Migration: if the existing table has no `group_id` column,
	//    do the recreate dance. Adding the column AND dropping the
	//    old (user_id, role) PRIMARY KEY constraint requires
	//    recreating - SQLite ALTER TABLE doesn't support either
	//    operation directly.
	var hasGroupID int
	db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('_benmore_user_roles') WHERE name='group_id'").Scan(&hasGroupID)
	if hasGroupID == 0 {
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("user_roles migration: begin: %w", err)
		}
		defer tx.Rollback()
		if _, err := tx.Exec(`CREATE TABLE _benmore_user_roles_new (
			user_id    INTEGER NOT NULL,
			role       TEXT    NOT NULL,
			group_id   TEXT,
			granted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			granted_by INTEGER,
			expires_at DATETIME
		)`); err != nil {
			return fmt.Errorf("user_roles migration: create new: %w", err)
		}
		if _, err := tx.Exec(`INSERT INTO _benmore_user_roles_new (user_id, role, granted_at, granted_by, expires_at)
			SELECT user_id, role, granted_at, granted_by, expires_at FROM _benmore_user_roles`); err != nil {
			return fmt.Errorf("user_roles migration: copy: %w", err)
		}
		if _, err := tx.Exec(`DROP TABLE _benmore_user_roles`); err != nil {
			return fmt.Errorf("user_roles migration: drop old: %w", err)
		}
		if _, err := tx.Exec(`ALTER TABLE _benmore_user_roles_new RENAME TO _benmore_user_roles`); err != nil {
			return fmt.Errorf("user_roles migration: rename: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("user_roles migration: commit: %w", err)
		}
		log.Printf("RBAC: migrated _benmore_user_roles to v2.7.59 schema (added group_id column)")
	}
	// 3. Indexes - idempotent; safe to run on a fresh table or after
	//    a migration.
	//    Uniqueness: (user_id, role, group_id) with NULL coalesced to
	//    '' so a single global grant can't coexist with another
	//    global grant of the same role. Group-scoped grants are still
	//    independent rows from globals.
	_, _ = db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_user_roles_uniq ON _benmore_user_roles(user_id, role, IFNULL(group_id, ''))`)
	_, _ = db.Exec(`CREATE INDEX IF NOT EXISTS idx_user_roles_expiry ON _benmore_user_roles(expires_at) WHERE expires_at IS NOT NULL`)
	return nil
}

// LoadSessionRoles reads every active role grant for `userID` from the
// join table, dedupes against the primary role from _benmore_users,
// and returns the resulting slice. Expired grants (expires_at <= now)
// are filtered out - they'll be GC'd later by the expiry sweeper but
// must not influence access decisions in the meantime.
//
// `primaryRole` is the value of _benmore_users.role and is ALWAYS
// included even when the join table has zero rows (back-compat: every
// pre-v2.7.54 user has exactly one role, just not via the join table).
//
// `effectiveGroupID` (v2.7.59+) scopes the join-table lookup to the
// session's active group context:
//   - empty string → return ONLY globally-scoped grants
//     (group_id IS NULL). Used for sessions without a group context
//     (no `groups:` config, or user has no group membership yet).
//   - non-empty → return globally-scoped grants PLUS those scoped to
//     this specific group (group_id = effective). Group-scoped grants
//     for OTHER groups are filtered out.
//
// The effective group is the act-as target when set, otherwise the
// user's native group. See Session.EffectiveGroupID. So an admin
// stepping into tenant Y temporarily loses any roles they hold ONLY
// in tenant X - which is the right semantic for "see the world as
// tenant Y."
func LoadSessionRoles(db *sql.DB, userID int64, primaryRole, effectiveGroupID string) []string {
	seen := map[string]bool{}
	out := []string{}
	if primaryRole != "" {
		seen[primaryRole] = true
		out = append(out, primaryRole)
	}
	// Query shape: globals (NULL group_id) always included. Group-
	// scoped grants included only when effectiveGroupID matches. We
	// branch on the empty-string case because `group_id = ''` would
	// otherwise match no rows but we want to clearly express "no
	// group context, only globals."
	var rows *sql.Rows
	var err error
	if effectiveGroupID == "" {
		rows, err = db.Query(`
			SELECT role FROM _benmore_user_roles
			WHERE user_id = ?
			  AND (expires_at IS NULL OR expires_at > datetime('now'))
			  AND group_id IS NULL`,
			userID)
	} else {
		rows, err = db.Query(`
			SELECT role FROM _benmore_user_roles
			WHERE user_id = ?
			  AND (expires_at IS NULL OR expires_at > datetime('now'))
			  AND (group_id IS NULL OR group_id = ?)`,
			userID, effectiveGroupID)
	}
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			continue
		}
		r = strings.TrimSpace(r)
		if r == "" || seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	return out
}

// UserHasGlobalAdminGrant reports whether the user holds a platform-global
// admin grant - an unexpired _benmore_user_roles row with role='admin' and
// group_id IS NULL. This (together with the _benmore_users.role column) is
// the ONLY source that may confer cross-tenant admin power; see
// Session.GlobalAdmin. Group-scoped admin grants and membership roles are
// deliberately excluded.
func UserHasGlobalAdminGrant(db *sql.DB, userID int64) bool {
	if db == nil || userID == 0 {
		return false
	}
	var n int
	err := db.QueryRow(`
		SELECT 1 FROM _benmore_user_roles
		WHERE user_id = ? AND role = 'admin' AND group_id IS NULL
		  AND (expires_at IS NULL OR expires_at > datetime('now'))
		LIMIT 1`, userID).Scan(&n)
	return err == nil
}

// HasAnyRole returns true when the session holds at least one of
// `wanted`. Admin role always satisfies the check - admins bypass
// role gates the same way they bypass owner-scoping.
func HasAnyRole(s *Session, wanted []string) bool {
	if s == nil {
		return false
	}
	// Admin shortcut - kept on the Role field for back-compat and
	// also checked against the multi-role slice (a user could be
	// admin via the join table without it being their primary role).
	if s.IsAdmin() {
		return true
	}
	for _, r := range s.Roles {
		if r == "admin" {
			return true
		}
	}
	for _, want := range wanted {
		want = strings.TrimSpace(want)
		if want == "" {
			continue
		}
		if s.Role == want {
			return true
		}
		for _, have := range s.Roles {
			if have == want {
				return true
			}
		}
	}
	return false
}

// HasPermission returns true when the session's effective scope set
// contains `perm`. Format mirrors scopes.go: "resource:action" (the
// access.go layer rewrites the user-facing `perm:posts.publish` to
// `posts:publish` before calling this). `*` and `<resource>:*` and
// the OAuth2 "write implies read" rule from hasScope are honored.
func HasPermission(s *Session, perm string) bool {
	if s == nil {
		return false
	}
	if s.IsAdmin() {
		return true
	}
	if perm == "" {
		return false
	}
	// Empty Scopes = no restriction (legacy cookie sessions).
	if s.Scopes == "" {
		return true
	}
	wantRes, wantAct := parseScope(perm)
	if wantRes == "" {
		return false
	}
	for _, tok := range strings.Fields(s.Scopes) {
		gotRes, gotAct := parseScope(tok)
		if gotRes == "" {
			continue
		}
		if gotRes == "*" {
			return true
		}
		if gotRes != wantRes {
			continue
		}
		if gotAct == "*" || gotAct == wantAct {
			return true
		}
		if wantAct == "read" && gotAct == "write" {
			return true
		}
	}
	return false
}

// StartRoleExpirySweeper runs a per-app background goroutine that
// periodically deletes expired role grants. Each evicted row is
// audit-logged so the trail mirrors explicit revokes.
//
// Cadence: every 5 minutes. Cheap query (single indexed scan), runs
// next to the existing CleanExpiredSessions worker on the same db
// handle.
func StartRoleExpirySweeper(app *App) {
	if app == nil || app.DB == nil {
		return
	}
	safeGo("rbac.roleExpirySweeper", func() {
		stop := app.Stop // capture once: hot reload reassigns app.Stop; reading the field in the loop would race the swap and could miss the close (goroutine leak)
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				sweepExpiredRoles(app)
			}
		}
	})
}

func sweepExpiredRoles(app *App) {
	rows, err := app.DB.Query(`
		SELECT user_id, role FROM _benmore_user_roles
		WHERE expires_at IS NOT NULL AND expires_at <= datetime('now')`)
	if err != nil {
		return
	}
	type expired struct {
		userID int64
		role   string
	}
	var batch []expired
	for rows.Next() {
		var e expired
		if err := rows.Scan(&e.userID, &e.role); err == nil {
			batch = append(batch, e)
		}
	}
	rows.Close()
	for _, e := range batch {
		res, err := app.DB.Exec(`
			DELETE FROM _benmore_user_roles
			WHERE user_id = ? AND role = ?
			  AND expires_at IS NOT NULL AND expires_at <= datetime('now')`,
			e.userID, e.role)
		if err != nil {
			continue
		}
		if n, _ := res.RowsAffected(); n > 0 {
			// System-driven eviction - no session, no user actor. The
			// pre-eviction state goes in oldRow so the audit trail shows
			// "this role existed, was removed by system:expiry".
			LogAudit(app, "role_expired", "_benmore_user_roles", strconv.FormatInt(e.userID, 10),
				nil, map[string]any{"user_id": e.userID, "role": e.role}, nil)
		}
	}
}

// RegisterRoleRoutes wires the admin endpoints. Mounted from
// buildAppMux alongside the rest of the framework routes.
func RegisterRoleRoutes(mux *http.ServeMux, app *App) {
	// GET /api/_auth/roles - discovery: every configured role +
	// its effective (post-inheritance) scope set. Authenticated;
	// admin-only when the app declares any roles (otherwise the
	// listing is empty anyway).
	mux.HandleFunc("GET /api/_auth/roles", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		// Admin-only (matches the doc above): the full role catalogue + effective
		// scopes is reconnaissance for in-tenant escalation (tells an attacker
		// which role name to target). A regular member has no need for it.
		if session == nil || !session.IsAdmin() {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "admin required"})
			return
		}
		out := make([]map[string]any, 0)
		if app.Roles != nil {
			for _, name := range app.Roles.KnownRoles() {
				def := app.Roles.Roles[name]
				out = append(out, map[string]any{
					"name":             name,
					"scopes":           def.Scopes,
					"inherits":         def.Inherits,
					"effective_scopes": app.Roles.ResolveRoleScopes(name),
				})
			}
		}
		httpJSON(w, http.StatusOK, map[string]any{"roles": out})
	})

	// GET /api/_auth/users/{id}/roles - list this user's active role
	// assignments. Admin OR self (a user is allowed to see their own
	// roles for client-side gating, but not anyone else's).
	mux.HandleFunc("GET /api/_auth/users/{id}/roles", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}
		uid, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil || uid <= 0 {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid user id"})
			return
		}
		if !session.IsAdmin() && session.UserID != uid {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
			return
		}
		// Pull the primary role from _benmore_users so the response
		// reflects the SAME effective set the auth layer evaluates.
		// The primary role is implicitly global - it has no group_id.
		var primary string
		_ = app.DB.QueryRow("SELECT COALESCE(role,'user') FROM _benmore_users WHERE id = ?", uid).Scan(&primary)
		assignments := []map[string]any{
			{"role": primary, "primary": true, "expires_at": nil, "group_id": nil},
		}
		// `seen` for the primary role's GLOBAL slot. Group-scoped
		// grants for the same role are NOT considered duplicates of
		// the global primary - they're meaningfully different (the
		// primary applies everywhere; the scoped one applies only in
		// its group). v2.7.59+ keys by (role, group_id) instead of
		// just role.
		seen := map[string]bool{primary + "|": true}
		rows, err := app.DB.Query(`
			SELECT role, granted_at, granted_by, expires_at, group_id
			FROM _benmore_user_roles
			WHERE user_id = ? AND (expires_at IS NULL OR expires_at > datetime('now'))
			ORDER BY role, IFNULL(group_id, '')`, uid)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var role, grantedAt string
				var grantedBy sql.NullInt64
				var expiresAt, groupID sql.NullString
				if err := rows.Scan(&role, &grantedAt, &grantedBy, &expiresAt, &groupID); err != nil {
					continue
				}
				key := role + "|"
				if groupID.Valid {
					key = role + "|" + groupID.String
				}
				if seen[key] {
					continue
				}
				seen[key] = true
				entry := map[string]any{
					"role":       role,
					"primary":    false,
					"granted_at": grantedAt,
				}
				if grantedBy.Valid {
					entry["granted_by"] = grantedBy.Int64
				}
				if expiresAt.Valid {
					entry["expires_at"] = expiresAt.String
				} else {
					entry["expires_at"] = nil
				}
				if groupID.Valid {
					entry["group_id"] = groupID.String
				} else {
					entry["group_id"] = nil
				}
				assignments = append(assignments, entry)
			}
		}
		// Computed conveniences mirror what the session would carry.
		// Note: this is the FULL set of role names the user holds in
		// ANY group - not the per-request filtered Roles slice. So
		// permissions here represent "what could they do somewhere,"
		// not "what they can do right now in this session."
		permissions := []string{}
		if app.Roles != nil {
			roleNames := []string{}
			for _, a := range assignments {
				roleNames = append(roleNames, a["role"].(string))
			}
			scopes := app.Roles.ResolveScopesForRoles(roleNames)
			if scopes != "" {
				permissions = strings.Fields(scopes)
			}
		}
		httpJSON(w, http.StatusOK, map[string]any{
			"user_id":     uid,
			"assignments": assignments,
			"permissions": permissions,
		})
	})

	// POST /api/_auth/users/{id}/roles - grant a role. Admin only.
	// Body: {role: "editor", expires_at?: "2026-12-31T23:59:59Z", group_id?: "1"}
	//
	// group_id (v2.7.59+) optional - when present, the grant applies
	// ONLY when the recipient is acting in that group's context.
	// When omitted (or empty / null), the grant is GLOBAL - applies
	// in every group context, identical to the v2.7.54 default.
	mux.HandleFunc("POST /api/_auth/users/{id}/roles", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil || !session.IsAdmin() {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "admin required"})
			return
		}
		if !isBearerAuth(r) && !validateCSRF(r) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
			return
		}
		uid, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil || uid <= 0 {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid user id"})
			return
		}
		var body struct {
			Role      string `json:"role"`
			ExpiresAt string `json:"expires_at"`
			GroupID   string `json:"group_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
			return
		}
		role := strings.TrimSpace(body.Role)
		if role == "" {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "role is required"})
			return
		}
		// Verify role exists in config (or is the special-cased "admin"/"user").
		if app.Roles != nil && role != "admin" && role != "user" {
			if _, ok := app.Roles.Roles[role]; !ok {
				httpJSON(w, http.StatusBadRequest, map[string]any{
					"error": fmt.Sprintf("role %q is not defined in app.yaml under roles:", role),
				})
				return
			}
		}
		// Verify the target user exists.
		var exists int
		_ = app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_users WHERE id = ?", uid).Scan(&exists)
		if exists == 0 {
			httpJSON(w, http.StatusNotFound, map[string]any{"error": "user not found"})
			return
		}
		var expiresAt any
		if body.ExpiresAt != "" {
			t, err := time.Parse(time.RFC3339, body.ExpiresAt)
			if err != nil {
				httpJSON(w, http.StatusBadRequest, map[string]any{"error": "expires_at must be RFC3339 (e.g. 2026-12-31T23:59:59Z)"})
				return
			}
			if t.Before(time.Now()) {
				httpJSON(w, http.StatusBadRequest, map[string]any{"error": "expires_at must be in the future"})
				return
			}
			expiresAt = t.UTC().Format("2006-01-02 15:04:05")
		}
		// group_id: empty → store NULL (global grant). Non-empty →
		// store the value. We do NOT validate against the
		// user_group_assignments table here - apps may use group
		// keys outside that table, or pre-create grants for groups
		// that don't exist yet. The grant simply has no effect
		// until a session is actually in that group context.
		var groupID any
		groupStr := strings.TrimSpace(body.GroupID)
		if groupStr != "" {
			groupID = groupStr
		}
		// Upsert keyed by the new (user_id, role, IFNULL(group_id, ''))
		// uniqueness - re-granting an existing (role, group) tuple
		// refreshes granted_by/expires_at/granted_at.
		_, err = app.DB.Exec(`
			INSERT INTO _benmore_user_roles (user_id, role, group_id, granted_by, expires_at)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(user_id, role, IFNULL(group_id, '')) DO UPDATE SET
				granted_by = excluded.granted_by,
				expires_at = excluded.expires_at,
				granted_at = CURRENT_TIMESTAMP`,
			uid, role, groupID, session.UserID, expiresAt)
		if err != nil {
			log.Printf("RBAC: grant failed user_id=%d role=%s err=%s", uid, role, err)
			httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "grant failed"})
			return
		}
		LogAudit(app, "role_granted", "_benmore_user_roles", strconv.FormatInt(uid, 10),
			session, nil, map[string]any{
				"user_id":    uid,
				"role":       role,
				"group_id":   groupID,
				"expires_at": expiresAt,
				"granted_by": session.UserID,
			})
		httpJSON(w, http.StatusOK, map[string]any{
			"user_id":    uid,
			"role":       role,
			"group_id":   groupID,
			"expires_at": expiresAt,
			"granted_by": session.UserID,
		})
	})

	// PATCH /api/_auth/users/{id}/roles/{role}[?group_id=X] - update
	// expires_at on an existing grant. Admin only. The grant is
	// targeted by (user_id, role, group_id) - omitting the query
	// param targets the GLOBAL grant (group_id IS NULL).
	mux.HandleFunc("PATCH /api/_auth/users/{id}/roles/{role}", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil || !session.IsAdmin() {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "admin required"})
			return
		}
		if !isBearerAuth(r) && !validateCSRF(r) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
			return
		}
		uid, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil || uid <= 0 {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid user id"})
			return
		}
		role := r.PathValue("role")
		groupID := strings.TrimSpace(r.URL.Query().Get("group_id"))
		var body struct {
			ExpiresAt string `json:"expires_at"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
			return
		}
		var expiresAt any
		if body.ExpiresAt != "" {
			t, err := time.Parse(time.RFC3339, body.ExpiresAt)
			if err != nil {
				httpJSON(w, http.StatusBadRequest, map[string]any{"error": "expires_at must be RFC3339"})
				return
			}
			expiresAt = t.UTC().Format("2006-01-02 15:04:05")
		}
		var res sql.Result
		if groupID == "" {
			res, err = app.DB.Exec(`
				UPDATE _benmore_user_roles SET expires_at = ?
				WHERE user_id = ? AND role = ? AND group_id IS NULL`,
				expiresAt, uid, role)
		} else {
			res, err = app.DB.Exec(`
				UPDATE _benmore_user_roles SET expires_at = ?
				WHERE user_id = ? AND role = ? AND group_id = ?`,
				expiresAt, uid, role, groupID)
		}
		if err != nil {
			httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "update failed"})
			return
		}
		if n, _ := res.RowsAffected(); n == 0 {
			httpJSON(w, http.StatusNotFound, map[string]any{"error": "grant not found"})
			return
		}
		LogAudit(app, "role_expiry_updated", "_benmore_user_roles", strconv.FormatInt(uid, 10),
			session, nil, map[string]any{
				"user_id":    uid,
				"role":       role,
				"expires_at": expiresAt,
			})
		httpJSON(w, http.StatusOK, map[string]any{"status": "updated"})
	})

	// DELETE /api/_auth/users/{id}/roles/{role}[?group_id=X] - revoke
	// a role. Admin only.
	//
	// Targeting (v2.7.59+): the join table has at most ONE grant per
	// (user, role, group_id). The endpoint targets a specific tuple:
	//   no query param            → revoke the GLOBAL grant (group_id IS NULL)
	//   ?group_id=X               → revoke the group-X-scoped grant only
	//   ?group_id=all (special)   → revoke EVERY (role, *) grant for this
	//                               user - convenience for full removal
	//
	// Refuses to revoke the user's primary role (the column on
	// _benmore_users) - that's a settings.go operation. Also refuses
	// self-revoke of the last GLOBAL admin (lockout protection); the
	// guard counts BOTH primary-column admins AND globally-scoped
	// join-table admin grants (group_id IS NULL) other than this one.
	// Group-scoped admin grants don't count toward "the last admin"
	// because they don't grant cross-tenant authority - removing them
	// can't lock the system out of admin.
	mux.HandleFunc("DELETE /api/_auth/users/{id}/roles/{role}", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil || !session.IsAdmin() {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "admin required"})
			return
		}
		if !isBearerAuth(r) && !validateCSRF(r) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
			return
		}
		uid, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil || uid <= 0 {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid user id"})
			return
		}
		role := r.PathValue("role")
		groupID := strings.TrimSpace(r.URL.Query().Get("group_id"))
		revokeAll := groupID == "all"
		// Lockout guard: only applies when revoking the GLOBAL admin
		// grant (group_id query param absent OR explicitly empty).
		// A self-revoke of a group-scoped admin doesn't risk
		// locking the system out - the user retains every other
		// grant they hold, and primary admins are unaffected.
		if uid == session.UserID && role == "admin" && groupID == "" {
			var others int
			_ = app.DB.QueryRow(`
				SELECT (
					(SELECT COUNT(*) FROM _benmore_users
						WHERE role = 'admin' AND id != ? AND (deactivated_at IS NULL OR deactivated_at = ''))
					+
					(SELECT COUNT(*) FROM _benmore_user_roles
						WHERE role = 'admin' AND user_id != ? AND group_id IS NULL
						  AND (expires_at IS NULL OR expires_at > datetime('now')))
				)`,
				session.UserID, session.UserID).Scan(&others)
			if others == 0 {
				httpJSON(w, http.StatusBadRequest, map[string]any{
					"error": "cannot revoke admin from the last active admin",
				})
				return
			}
		}
		var res sql.Result
		switch {
		case revokeAll:
			res, err = app.DB.Exec("DELETE FROM _benmore_user_roles WHERE user_id = ? AND role = ?", uid, role)
		case groupID == "":
			res, err = app.DB.Exec("DELETE FROM _benmore_user_roles WHERE user_id = ? AND role = ? AND group_id IS NULL", uid, role)
		default:
			res, err = app.DB.Exec("DELETE FROM _benmore_user_roles WHERE user_id = ? AND role = ? AND group_id = ?", uid, role, groupID)
		}
		if err != nil {
			httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "revoke failed"})
			return
		}
		if n, _ := res.RowsAffected(); n == 0 {
			httpJSON(w, http.StatusNotFound, map[string]any{"error": "grant not found"})
			return
		}
		auditScope := groupID
		if revokeAll {
			auditScope = "all"
		}
		LogAudit(app, "role_revoked", "_benmore_user_roles", strconv.FormatInt(uid, 10),
			session, map[string]any{
				"user_id":  uid,
				"role":     role,
				"group_id": auditScope,
			}, map[string]any{
				"user_id":    uid,
				"role":       role,
				"group_id":   auditScope,
				"revoked_by": session.UserID,
			})
		httpJSON(w, http.StatusOK, map[string]any{"status": "revoked", "group_id": auditScope})
	})
}
